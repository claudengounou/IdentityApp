import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { SharedService } from 'src/app/shared/shared.service';
import { AccountService } from '../account.service';
import { take } from 'rxjs';
import { User } from 'src/app/shared/models/account/user';
import { RegisterWithExternal } from 'src/app/shared/models/account/registerWithExternal';

@Component({
  selector: 'app-register-with-third-party',
  templateUrl: './register-with-third-party.component.html',
  styleUrls: ['./register-with-third-party.component.css']
})
export class RegisterWithThirdPartyComponent implements OnInit {
 registerForm: FormGroup = new FormGroup({});
 submitted = false;
 provider: string | null = null;
 access_token: string | null = null;
 userId: string | null = null;
 errorMessages: string[] = [];
  
  constructor(
    private formBuilder: FormBuilder,
    private sharedService: SharedService,
    private router: Router,
    private activatedRoute: ActivatedRoute,
    private accountService: AccountService
  ){}
  
  ngOnInit(): void {
    this.accountService.user$.pipe(take(1)).subscribe({
      next: (user: User | null) => {
        if(user){
          this.router.navigateByUrl("/");
        } else {
          this.activatedRoute.queryParamMap.subscribe({
            next: (params : any) => {
             this.provider = this.activatedRoute.snapshot.paramMap.get('provider'); 
             this.access_token = params.get('access_token');
             this.userId = params.get('userId');
             
             if(this.userId && this.access_token  
              && (this.provider ==='facebook' || this.provider ==='google')){
                this.initializeForm();
              } else {
                this.router.navigateByUrl('/account/register')
              }
            }
          });
        }
      }
    });
  }

  
  initializeForm() {
    this.registerForm = this.formBuilder.group({
      firstName: [
        '',
        [
          Validators.required,
          Validators.minLength(3),
          Validators.maxLength(15),
        ],
      ],
      lastName: [
        '',
        [
          Validators.required,
          Validators.minLength(3),
          Validators.maxLength(15),
        ],
      ]
    });
  }

  register(){
    this.submitted = true;
    this.errorMessages = [];

    if(this.registerForm.valid && this.userId && this.access_token && this.provider){
      console.log(this.registerForm.get('firstName')?.value);
      const firstName = this.registerForm.get('firstName')?.value;
      const lastName = this.registerForm.get('lastName')?.value;

      const model = new RegisterWithExternal(firstName, lastName, this.userId, this.access_token, this.provider);
      
      this.accountService.registerWithThirdParty(model).subscribe({
        next: _ => {
          this.router.navigateByUrl('/');
        },
        error: (error) => {
          if (error.error.errors) {
            this.errorMessages = error.error.errors;
          } else {
            this.errorMessages.push(error.error);
          }
        }
      });

    }
  }
  
}
